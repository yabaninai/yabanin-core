// Group-key fingerprint law (E06-P01 W02-C01).
//
// One incident per finding: two events fold into the same incident row when
// they describe the SAME finding. That equivalence is the group key — a
// deterministic SHA-256 fingerprint of three dimensions:
//
//	key = sha256(GroupKeyVersion "|" category "|" severity "|" resourceDigest)
//
//   - category is the full dotted event type (e.g. "tool.deny"). It is the
//     finding class namespace on the v1 wire; coarser prefixes would merge
//     unrelated findings, so the whole type is used verbatim.
//   - severity is the finding's severity verdict. It is part of the key so a
//     severity change SPLITS incidents (the W02-C03 split-on-severity-change
//     knob composes with this law). Until W03-C01 wires real verdicts the
//     provisional constant (SeverityLow) stands in — constant today, but the
//     key formula already carries it, so wiring verdicts later cannot change
//     the law's shape.
//   - resourceDigest is sha256 of the affected resource tuple: the non-empty
//     identity references in the fixed order agent, session, task, tool,
//     joined as "kind=value" with unit separators. Order comes from the
//     fixed tuple, never from input order.
//
// Privacy law: only DIGESTS enter the key. Raw content — Summary text,
// evidence digests, cost, unknown wire fields, occurred_at, event_id — never
// does. Two events that differ ONLY in raw content produce the SAME key;
// the battery pins that. OrgID is deliberately NOT in the key: the key
// identifies a finding class, and cross-org isolation is the store's job —
// the (org_id, group_key) unique row plus RLS (W01-C01/C02 batteries), so
// the same finding in two orgs shares the key string across two isolated
// rows.
//
// Versioning: GroupKeyVersion prefixes the hash input. Any future change to
// the derivation bumps the version, which changes every key and re-folds
// fresh incidents — safe because the inbox is derived, rebuildable state
// (old rows simply stop matching new keys; the projection law documents the
// same property for the W01→W02 key changeover).

package inbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// GroupKeyVersion labels the group-key derivation law (see the file comment).
const GroupKeyVersion = "e06p01.v1"

// ErrGroupKeyNoCategory reports a group-key derivation over an event with an
// empty event type — there is no finding class to fingerprint, so the fold
// refuses the event instead of inventing a key for garbage.
var ErrGroupKeyNoCategory = errors.New("inbox: group key: event type is empty")

// GroupKey derives the deterministic incident fingerprint for one event
// under the default grouping policy (the law is documented at the top of
// this file; the policy's severity slot is documented in grouping.go). It
// is pure: no clock, no randomness, no store — the same event always
// yields the same key.
func GroupKey(e secevents.Event) (string, error) {
	return GroupKeyFor(DefaultGroupPolicy(), e, provisionalSeverity)
}

// ResourceDigest fingerprints the affected resource of an event: the non-empty
// identity references in the fixed order agent, session, task, tool. Content-
// bearing fields never enter (privacy law above). The result is itself a hex
// digest, so the outer key never exposes the raw identifiers either.
func ResourceDigest(e secevents.Event) string {
	parts := make([]string, 0, 4)
	for _, ref := range []struct {
		kind string
		r    secevents.IDRef
	}{
		{"agent", e.Identity.Agent},
		{"session", e.Identity.Session},
		{"task", e.Identity.Task},
		{"tool", e.Identity.Tool},
	} {
		if ref.r.Value != "" {
			parts = append(parts, ref.kind+"="+ref.r.Value)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}
