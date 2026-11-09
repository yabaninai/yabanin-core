package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// policyCacheRegime resolves the cache identity's tenant-policy fingerprint
// for one org (N03-P02-T03: bind the cache identity to the tenant policy).
// The fingerprint is derived from the org's currently compiled policy
// snapshot — the policystore version (when known) plus every compiled plan's
// identity — so any policy attach/update/tighten through the control plane
// (which publishes the Redis version key) changes the fingerprint and
// degrades warm entries stored under the earlier regime to misses on every
// cache layer.
//
// The chat lookup path reaches this through the request-scoped policy
// outcome, so on the hot path no extra store read happens beyond the one the
// pre-upstream enforcement already made. The detached stream-write context
// falls back to a version probe — the same read the enforcement path pays.
//
// "" means "enforcement off or unverifiable" (N03-P02-T04): the runtime is
// unwired or cold-unavailable, it runs with policy mode off (no policy
// checking at all — pre-upstream enforcement no-ops, so there is no snapshot
// the cache could claim to be bound to), the org is empty, or no snapshot
// could be loaded. The cache service answers with no lookup and no write for
// the org at all: enforcement-off is preserved without reads and writes, not
// "read and filter". This closes the bypass window where an untagged entry
// written while off could be served by a later lookup whose regime
// resolution transiently failed — a replay with no re-governance at all.
// When enforcement runs (enforce and shadow both keep policy checking
// active), the fingerprint binds entries to the governing snapshot and the
// serve-time re-governance (policyPostUpstream) remains the governing
// control — fail-safe, never permissive.
func (gw *gateway) policyCacheRegime(ctx context.Context, orgID string) string {
	rt := gw.policyRuntime
	if rt == nil || rt.coldUnavailable || rt.mode == PolicyModeOff || orgID == "" {
		return ""
	}
	e := rt.requestOutcome(ctx, orgID).entry
	if e == nil {
		return ""
	}
	return policySnapshotFingerprint(e)
}

// policySnapshotFingerprint hashes the material identity of a compiled org
// policy snapshot: the store version when known (haveVer — the value the
// control-plane bumper publishes on every mutation), plus every compiled
// plan's identity (policy id, version, judge prompt version) in canonical
// order. Entries are immutable after load and replaced on reload, so equal
// inputs imply an equal snapshot; any attach, update or tighten yields a
// different digest. The digest is stable across replicas and restarts.
func policySnapshotFingerprint(e *orgPolicyEntry) string {
	buf := make([]byte, 0, 64+len(e.plans)*32)
	if e.haveVer {
		buf = append(buf, []byte(fmt.Sprintf("ver=%d\n", e.version))...)
	} else {
		buf = append(buf, "ver=unknown\n"...)
	}
	ids := make([]string, 0, len(e.plans))
	for _, p := range e.plans {
		ids = append(ids, fmt.Sprintf("plan=%s:%d:%s", p.policyID, p.version, p.judgeVersion))
	}
	sort.Strings(ids)
	for _, id := range ids {
		buf = append(buf, id...)
		buf = append(buf, '\n')
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8])
}
